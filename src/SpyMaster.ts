import {
    RuntimeModule,
    runtimeMethod,
    state,
    runtimeModule,
  } from "@proto-kit/module";
import { State, StateMap, assert } from "@proto-kit/protocol";
import {
  Bool,
  Experimental,
  Field,
  MerkleMapWitness,
  Nullifier,
  Poseidon,
  Struct,
  Character,
  Provable,
  UInt64,
} from "o1js";
import { inject } from "tsyringe";
import { Balances } from "./Balances";

export class SecurityCode extends Struct({
  char0: Field,
  char1: Field,
}) {};

export class AgentId extends UInt64 {}

export class Message extends Struct({
  messageNumber: UInt64,
  agentId: AgentId,
  body: Provable.Array(Field, 12),
  securityCode: SecurityCode,
}) {}

export class Agent extends Struct({
  agentId: AgentId,
  lastMessage: UInt64,
  securityCode: SecurityCode,
}) {}

type SpyMasterConfig = Record<string, never>;

@runtimeModule()
export class SpyMaster extends RuntimeModule<SpyMasterConfig> {
  @state() public agents = StateMap.from<AgentId, Agent>(
    AgentId,
    Agent
  );

  @runtimeMethod()
  public addAgent(agentId: AgentId, securityCode: SecurityCode) {
    this.agents.set(agentId, new Agent({
      agentId: agentId,
      lastMessage: UInt64.from(0),
      securityCode: securityCode,
    }));
  }

  setLastMessage(agentId: AgentId, lastMessage: UInt64) {
    const agent = this.agents.get(agentId).value;
    const newAgent = new Agent({
      agentId: agent.agentId,
      lastMessage: lastMessage,
      securityCode: agent.securityCode,
    });
    this.agents.set(agentId, agent);
  }

  @runtimeMethod()
  public processMessage(message: Message) {
    // Check that the agent exists
    const agent = this.agents.get(message.agentId).value;
    // Check that the security code matches the agent's security code
    assert(Bool.and(
        agent.securityCode.char0.equals(message.securityCode.char0), 
        agent.securityCode.char1.equals(message.securityCode.char1)
    ), "Security code does not match");
    // Check that the message body is 12 characters long
    assert(UInt64.from(message.body.length).equals(UInt64.from(12)));
    // Check that the message number is greater than the agent's last message
    console.log("message.messageNumber", message.messageNumber.toString());
    console.log("agent.lastMessage", agent.lastMessage.toString());
    assert(message.messageNumber.greaterThan(agent.lastMessage));
    // Update the agent's last message
    this.setLastMessage(message.agentId, message.messageNumber);
    const agent2 = this.agents.get(message.agentId).value;
    console.log("agent2.lastMessage", agent2.lastMessage.toString());
  };

}