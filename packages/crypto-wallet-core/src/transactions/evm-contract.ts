import { type Contract, eth, utils, validator } from 'web3';
import type { AbiItem } from 'web3-utils';

type ContractGetter = (address: string) => Contract<AbiItem[]>;
const snapshots = new WeakMap<AbiItem[], AbiItem[]>();

export function registerContractAbi(abi: AbiItem[]) {
  snapshots.set(abi, JSON.parse(JSON.stringify(abi)));
}

function matchesAbi(value: unknown, snapshot: unknown): boolean {
  if (value === snapshot) return true;
  if (!value || !snapshot || typeof value !== 'object' || typeof snapshot !== 'object' ||
      Object.getPrototypeOf(value) !== Object.getPrototypeOf(snapshot)) return false;

  const keys = Reflect.ownKeys(snapshot);
  if (Reflect.ownKeys(value).length !== keys.length) return false;
  return keys.every(key => {
    const property = Object.getOwnPropertyDescriptor(value, key);
    return property && 'value' in property &&
      property.enumerable === Object.prototype.propertyIsEnumerable.call(snapshot, key) &&
      matchesAbi(property.value, snapshot[key]);
  });
}

export function createContractEncoder(abi: AbiItem[], defaultGetter: ContractGetter) {
  const snapshot = snapshots.get(abi);
  const methods = new Map<string, { inputs: NonNullable<AbiItem['inputs']>; selector: string } | undefined>();

  return (provider: object, getter: ContractGetter, address: string) => {
    // Fresh contracts also share nested ABI data with the exported ABI. Use Web3 when it changes.
    // Preserve overridden getters and Web3's handling of invalid addresses and constructor overloads.
    // The default constructor accepts unchecksummed addresses and checksums them for storage only.
    if (!snapshot || getter !== defaultGetter ||
        (address !== undefined && address !== '' && (typeof address !== 'string' || !utils.isAddress(address, false))) ||
        !matchesAbi(abi, snapshot)) {
      const contract = getter.call(provider, address);
      return (name: string, ...args: unknown[]) => contract.methods[name](...args).encodeABI();
    }

    return (name: string, ...args: unknown[]) => {
      if (!methods.has(name)) {
        const fragments = snapshot.filter(eth.abi.isAbiFunctionFragment).filter(fragment => fragment.name === name);
        const [fragment] = fragments;
        const inputs = fragment?.inputs;
        // Web3 transforms tuples and resolves overloads before validating arguments. The builders'
        // single, non-tuple methods can validate their positional arguments as supplied.
        const method = fragments.length === 1 && inputs && inputs.every(input => !input.type.startsWith('tuple'))
          ? { inputs, selector: eth.abi.encodeFunctionSignature(fragment) }
          : undefined;
        methods.set(name, method);
      }
      const method = methods.get(name);
      if (!method) {
        return getter.call(provider, address).methods[name](...args).encodeABI();
      }
      const params = args.length === method.inputs.length
        ? args
        : validator.utils.transformJsonDataToAbiFormat(method.inputs, args);
      validator.validator.validate(method.inputs, params);
      return method.selector + eth.abi.encodeParameters(method.inputs, params).slice(2);
    };
  };
}
