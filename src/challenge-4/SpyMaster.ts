import {
    RuntimeModule,
    runtimeMethod,
    state,
    runtimeModule,
  } from "@proto-kit/module";
  import { State, StateMap } from "@proto-kit/protocol";
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
    PublicKey,
  } from "o1js";
  import { inject } from "tsyringe";
  import { Balances } from "./Balances";
  import { transaction } from "o1js/dist/node/lib/mina";
  
  export class SecurityCode extends Struct({
    char0: Field,
    char1: Field,
  }) {}
  
  export class AgentId extends UInt64 {}
  
  export class Message extends Struct({
    messageNumber: UInt64,
    agentId: AgentId,
    body: Provable.Array(Field, 12),
    securityCode: SecurityCode,
  }) {}
  
  export class BlockInfo extends Struct({
    blockHeight: UInt64,
    transactionSender: PublicKey,
    senderNonce: UInt64,
  }) {}
  
  export class Agent extends Struct({
    agentId: AgentId,
    lastMessage: UInt64,
    securityCode: SecurityCode,
  }) {
    constructor(agentId: AgentId, lastMessage: UInt64, securityCode: SecurityCode) {
        super({
            agentId,
            lastMessage,
            securityCode,
        });
    }
  }


export class ExtendedAgent extends Agent {
    blockInfo: BlockInfo;
    constructor(agentId: AgentId, lastMessage: UInt64, securityCode: SecurityCode, blockInfo: BlockInfo) {
        super(agentId, lastMessage, securityCode);
        this.blockInfo = blockInfo;
    }
}
  
  // ZkProgram
  export const PrivateMessage = Experimental.ZkProgram({
    publicInput: ExtendedAgent,
    publicOutput: UInt64,
    methods: {
      process: {
        privateInputs: [Message],
  
        method(agent: ExtendedAgent, message: Message): UInt64 {
          // Check that the security code matches the agent's security code
          Bool.and(
            agent.securityCode.char0.equals(message.securityCode.char0),
            agent.securityCode.char1.equals(message.securityCode.char1),
          ).assertTrue("Security code does not match");
          // Check that the message body is 12 characters long
          UInt64.from(message.body.length).assertEquals(UInt64.from(12));
          // Check that the message number is greater than the agent's last message
          message.messageNumber.assertGreaterThan(
            agent.lastMessage,
            "Message number is not greater than the agent's last message",
          );
          // Return the message number
          return message.messageNumber;
        },
      },
    },
  });
  
  export class PrivateMessageProof extends Experimental.ZkProgram.Proof(
    PrivateMessage,
  ) {}
  
  // Runtime Module
  type SpyMasterConfig = Record<string, never>;
  
  @runtimeModule()
  export class SpyMaster extends RuntimeModule<SpyMasterConfig> {
    @state() public agents = StateMap.from<AgentId, Agent>(AgentId, Agent);
  
    @runtimeMethod()
    public setLastMessage(agentId: AgentId, privateMessageProof: PrivateMessageProof) {
      // Verify the proof of message validity
      privateMessageProof.verify();
      const agent = this.agents.get(agentId).value;
      const newAgent = new Agent(
          agent.agentId,
          privateMessageProof.publicOutput,
          agent.securityCode,
      );
      this.agents.set(agentId, newAgent);
    }
  
    // Auxiliary method to add an agent for testing purposes
    @runtimeMethod()
    public addAgent(agentId: AgentId, securityCode: SecurityCode) {
      this.agents.set(
        agentId,
        new Agent(
          agentId,
          UInt64.from(0),
          securityCode,
        ),
      );
    }
  }

  @runtimeModule()
  export class ExtendedSpyMaster extends SpyMaster {
    @state() public _agents = StateMap.from<AgentId, ExtendedAgent>(AgentId, ExtendedAgent);
    @state() public blockHeights = StateMap.from<UInt64, AgentId>(UInt64, AgentId);
  
    @runtimeMethod()
    public override setLastMessage(agentId: AgentId, privateMessageProof: PrivateMessageProof) {
      // Verify the proof of message validity
      privateMessageProof.verify();
      const agent = this.agents.get(agentId).value;
      const block = new BlockInfo({
          blockHeight: this.network.block.height,
          transactionSender: this.transaction.sender,
          senderNonce: this.transaction.nonce,
          });
      const newAgent = new ExtendedAgent(
          agent.agentId,
          privateMessageProof.publicOutput,
          agent.securityCode,
          block,
      );
      this.agents.set(agentId, newAgent);
      this.blockHeights.set(block.blockHeight, agentId);
    }
  
    // Auxiliary method to add an agent for testing purposes
    @runtimeMethod()
    public addAgent(agentId: AgentId, securityCode: SecurityCode) {
      const block = new BlockInfo({
          blockHeight: this.network.block.height,
          transactionSender: this.transaction.sender,
          senderNonce: this.transaction.nonce,
          });
      this.agents.set(
        agentId,
        new ExtendedAgent(
          agentId,
          UInt64.from(0),
          securityCode,
          block,
        ),
      );
    }
  }