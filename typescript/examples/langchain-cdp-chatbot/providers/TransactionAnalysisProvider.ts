import { z } from "zod";
import { CreateAction } from "@coinbase/agentkit";
import { ActionProvider } from "@coinbase/agentkit";
import { Network } from '@coinbase/agentkit';
import { ethers } from 'ethers';

// Types (txs)
interface TransactionRisk {
  riskLevel: 'safe' | 'warning' | 'danger';
  reason: string;
  recommendation: string;
}

interface TransactionConfig {
  basescanApiKey: string;
  rpcUrl: string;
  supportedNetworks?: Network[];
  apiUrl?: string,
  apiKey?: any
}

// Types (user level)
interface UserProgress {
  address: string;
  xp: number;
  level: number;
  transactionsAnalyzed: number;
  lastUpdate: number;
  achievements: Achievement[];
}

interface Achievement {
  id: string;
  name: string;
  description: string;
  xpReward: number;
  dateUnlocked: number;
}

interface XPEvent {
  action: string;
  baseXP: number;
  multiplier: number;
  description: string;
}

// Schemas
const MonitorAddressSchema = z.object({
  userAddress: z.string().describe("Address to monitor"),
  currentLevel: z.number().min(1).max(100).describe("Current user level (1-100)")
});

const AnalyzeTransactionSchema = z.object({
  txHash: z.string().describe("Transaction hash to analyze"),
  userLevel: z.number().min(1).max(100).describe("User's current level (1-100)"),
  isNewTransaction: z.boolean().describe("Whether this is a new transaction that just occurred")
});

const UpdateUserProgressSchema = z.object({
  userAddress: z.string(),
  action: z.enum(['TRANSACTION_ANALYZED', 'SAFE_TRANSACTION', 'COMPLEX_INTERACTION', 'FIRST_DEFI', 'ACHIEVEMENT_UNLOCKED']),
  context: z.object({
    transactionHash: z.string().optional(),
    achievementId: z.string().optional(),
    complexity: z.number().optional(),
  }).optional(),
});

/**
 * TransactionAnalysisProvider to analyse transactions
 */
export class TransactionAnalysisProvider extends ActionProvider {
  private lastKnownTx: Record<string, string>;
  private readonly basescanApiKey: string;
  private readonly provider: ethers.JsonRpcProvider;
  private readonly supportedNetworks: Network[];
  private readonly apiUrl: string;
  private readonly apiKey: string;

  // Level variables
  private readonly XP_ACTIONS: Record<string, XPEvent> = {
    TRANSACTION_ANALYZED: { action: 'Transaction Analysis', baseXP: 10, multiplier: 1, description: 'Analyzed a transaction' },
    SAFE_TRANSACTION: { action: 'Safe Transaction', baseXP: 20, multiplier: 1.2, description: 'Completed a safe transaction' },
    COMPLEX_INTERACTION: { action: 'Complex Interaction', baseXP: 30, multiplier: 1.5, description: 'Handled complex contract interaction' },
    FIRST_DEFI: { action: 'DeFi Pioneer', baseXP: 50, multiplier: 2, description: 'First DeFi interaction' },
    ACHIEVEMENT_UNLOCKED: { action: 'Achievement', baseXP: 100, multiplier: 1, description: 'Unlocked new achievement' },
  };
  private readonly LEVEL_THRESHOLDS = {
    calculateXPForLevel: (level: number) => Math.floor(100 * Math.pow(1.5, level - 1)),
    getMaxLevel: () => 100
  };

  constructor(config: TransactionConfig) {
    super("enhanced_transaction_analysis", []);
    this.lastKnownTx = {};
    this.basescanApiKey = config.basescanApiKey;
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.supportedNetworks = config.supportedNetworks || [
      { 
          protocolFamily: 'base',
          networkId: 'base-mainnet',
          chainId: '8453'
      }
    ];
    this.apiUrl = config.apiUrl || 'http://localhost:3000';
    this.apiKey = config.apiKey;
  }

  supportsNetwork(network: Network): boolean {
    return this.supportedNetworks.some(supported => 
      supported.protocolFamily === network.protocolFamily &&
      supported.networkId === network.networkId &&
      supported.chainId === network.chainId
    );
  }

  private async getLatestTransaction(address: string): Promise<ethers.TransactionResponse | null> {
    try {
        // Use API go get address tx history
        const baseUrl = "https://api.basescan.org/api";
        const response = await fetch(
            `${baseUrl}?module=account&action=txlist&address=${address}&sort=desc&apikey=${this.basescanApiKey}&limit=1`
        );
        
        const data = await response.json();
        
        if (data.status === "1" && data.result.length > 0) {
            const tx = await this.provider.getTransaction(data.result[0].hash);
            return tx;
        }
        
        return null;
    } catch (error) {
        console.error('Error fetching latest transaction:', error);
        return null;
    }
  }

  @CreateAction({
    name: "monitor_address",
    description: "Monitors an address for new transactions and provides real-time analysis",
    schema: MonitorAddressSchema
  })
  async monitorAddress(args: z.infer<typeof MonitorAddressSchema>): Promise<string> {
    const { userAddress, currentLevel } = args;

    try {
      const latestTx = await this.getLatestTransaction(userAddress);
      
      if (!latestTx) {
        return "No transactions found for this address.";
      }

      if (latestTx.hash !== this.lastKnownTx[userAddress]) {
        this.lastKnownTx[userAddress] = latestTx.hash;
        
        return await this.analyzeTransaction({
          txHash: latestTx.hash,
          userLevel: currentLevel,
          isNewTransaction: true
        });
      }

      return "No new transactions.";
    } catch (error) {
      return `Error monitoring address: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }

  @CreateAction({
      name: "analyze_transaction",
      description: "Analyzes a specific transaction with user-level-appropriate explanations",
      schema: AnalyzeTransactionSchema
  })
  async analyzeTransaction(args: z.infer<typeof AnalyzeTransactionSchema>): Promise<string> {
    const { txHash, userLevel, isNewTransaction } = args;

    try {
        const tx = await this.provider.getTransaction(txHash);
        if (!tx) throw new Error('Transaction not found');

        const receipt = await this.provider.getTransactionReceipt(txHash);
        if (!receipt) throw new Error('Transaction receipt not found');

        const riskAnalysis = await this.assessTransactionRisk(tx, receipt);
        const explanation = await this.generateLevelAppropriateExplanation(tx, receipt, userLevel);

        // Save explanation in DB
        await fetch(`${this.apiUrl}/explanation`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.apiKey
          },
          body: JSON.stringify({
            transactionHash: txHash,
            userLevel,
            explanation,
            riskAnalysis: this.formatRiskAlert(riskAnalysis),
            userAddress: tx.from
          })
        });
        
        // Update user progression
        await this.updateUserProgress({
            userAddress: tx.from,
            action: 'TRANSACTION_ANALYZED',
            context: {
                transactionHash: txHash,
                complexity: await this.calculateTransactionComplexity(txHash)
            }
        });

        return `
            ${isNewTransaction ? '🆕 New Transaction Detected!' : 'Transaction Analysis:'}
            
            ${explanation}
            
            ${this.formatRiskAlert(riskAnalysis)}
        `;
    } catch (error) {
        return `Error analyzing transaction: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }

  private async isVerifiedContract(address: string): Promise<boolean> {
    try {
      const response = await fetch(
        `https://api.basescan.org/api?module=contract&action=getabi&address=${address}&apikey=${this.basescanApiKey}`
      );
      const data = await response.json();
      return data.status === '1' && data.result !== 'Contract source code not verified';
    } catch {
      return false;
    }
  }

  private determineTransactionType(tx: ethers.TransactionResponse): string {
    if (!tx.data || tx.data === '0x') return 'ETH Transfer';
    if (tx.data.startsWith('0xa9059cbb')) return 'ERC20 Transfer';
    if (tx.data.startsWith('0x23b872dd')) return 'ERC20 TransferFrom';
    return 'Contract Interaction';
  }

  private formatEvents(logs: readonly ethers.Log[] | ethers.Log[]): string {
    return logs.map((log, index) => `Event ${index + 1}: ${log.topics[0]}`).join('\n');
  }

  private formatRiskAlert(risk: TransactionRisk): string {
    return `
      Risk Assessment:
      Level: ${risk.riskLevel.toUpperCase()}
      ${risk.reason}
      
      Recommendation: ${risk.recommendation}
    `;
  }

  private async assessTransactionRisk(
    tx: ethers.TransactionResponse,
    receipt: ethers.TransactionReceipt
  ): Promise<TransactionRisk> {
    try {
      // Convert to ETH because more readable
      const valueInEth = Number(ethers.formatEther(tx.value));
      const gasUsed = receipt.gasUsed;
      const gasLimit = tx.gasLimit;
  
      // Risk factors
      const riskFactors = {
        highValue: valueInEth > 1, // Transaction > 1 ETH
        unusualGas: gasUsed > (gasLimit * BigInt(8)) / BigInt(10), // Use of more than 80% of gas limit
        newContract: tx.to ? !(await this.isVerifiedContract(tx.to)) : true,
        failedTx: receipt.status === 0,
        complexData: tx.data && tx.data.length > 138, // Complex data (simple than transfer)
        highGasPrice: tx.gasPrice > ethers.parseUnits("100", "gwei") // Gas price > 100 gwei
      };
  
      if (riskFactors.failedTx) {
        return {
          riskLevel: 'warning',
          reason: '⚠️ La transaction a échoué',
          recommendation: 'Vérifiez les paramètres de la transaction et le solde de votre compte avant de réessayer.'
        };
      }
  
      // Analyze combined risks
      if (riskFactors.highValue && riskFactors.newContract) {
        return {
          riskLevel: 'danger',
          reason: '🚨 Transaction de valeur élevée avec un contrat non vérifié',
          recommendation: 'Vérifiez attentivement le contrat et ses audits avant de procéder. Considérez faire une transaction test avec un petit montant.'
        };
      }
  
      if (riskFactors.unusualGas && riskFactors.complexData) {
        return {
          riskLevel: 'warning',
          reason: '⚠️ Transaction complexe avec une utilisation élevée de gas',
          recommendation: 'Vérifiez que vous comprenez toutes les actions que cette transaction va effectuer.'
        };
      }
  
      if (riskFactors.highGasPrice) {
        return {
          riskLevel: 'warning',
          reason: '⚠️ Prix du gas inhabituellement élevé',
          recommendation: 'Considérez attendre que le prix du gas baisse pour effectuer cette transaction.'
        };
      }
  
      // Standard transaction
      return {
        riskLevel: 'safe',
        reason: '✅ Transaction standard sans risques particuliers détectés',
        recommendation: 'Vous pouvez procéder avec confiance.'
      };
    } catch (error) {
      console.error('Error in risk assessment:', error);
      return {
        riskLevel: 'warning',
        reason: '⚠️ Impossible d\'effectuer une analyse complète des risques',
        recommendation: 'Procédez avec prudence et vérifiez tous les paramètres.'
      };
    }
  }
  
  private async generateLevelAppropriateExplanation(
    tx: ethers.TransactionResponse,
    receipt: ethers.TransactionReceipt,
    userLevel: number
  ): Promise<string> {
    try {
      const valueInEth = ethers.formatEther(tx.value);
      const gasCost = tx.gasPrice * receipt.gasUsed;
      const gasCostInEth = gasCost ? ethers.formatEther(gasCost) : '0';
      const txType = this.determineTransactionType(tx);
  
      // Beginner level (1-20)
      if (userLevel <= 20) {
        let explanation = `
          📝 Explication Simple:
          
          ${tx.value > BigInt(0) 
            ? `- Vous avez envoyé ${valueInEth} ETH`
            : `- Vous avez interagi avec ${tx.to ? 'une application' : 'un nouveau contrat'}`
          }
          
          - La transaction est ${receipt.status ? 'réussie ✅' : 'échouée ❌'}
          - Frais payés: ${gasCostInEth} ETH
          
          ${receipt.status ? '👍 Tout s\'est bien passé!' : '😕 Quelque chose n\'a pas fonctionné.'}
        `;
        return explanation;
      }
  
      // Intermediate level (21-60)
      if (userLevel <= 60) {
        let explanation = `
          🔍 Détails de la Transaction:
          
          - Type: ${txType}
          - Montant: ${valueInEth} ETH
          - Destinataire: ${tx.to || 'Création de contrat'}
          - Gas utilisé: ${receipt.gasUsed.toString()} unités
          - Coût total: ${gasCostInEth} ETH
          - Status: ${receipt.status ? 'Succès' : 'Échec'}
          
          ${tx.data !== '0x' ? '🤖 Cette transaction a interagi avec un smart contract.' : ''}
        `;
        return explanation;
      }
  
      // Advanced level (61-100)
      return `
        🔬 Analyse Technique Détaillée:
        
        Transaction:
        - Hash: ${tx.hash}
        - Block: ${tx.blockNumber}
        - Nonce: ${tx.nonce}
        - From: ${tx.from}
        - To: ${tx.to || 'Contract Creation'}
        - Value: ${valueInEth} ETH
        
        Gas:
        - Limite: ${tx.gasLimit.toString()}
        - Utilisé: ${receipt.gasUsed.toString()} (${(receipt.gasUsed * 100n / tx.gasLimit).toString()}%)
        - Prix: ${ethers.formatUnits(tx.gasPrice || 0, 'gwei')} Gwei
        - Coût Total: ${gasCostInEth} ETH
        
        Données:
        - Input: ${tx.data}
        ${tx.data !== '0x' ? `- Function: ${tx.data.slice(0, 10)}` : ''}
        
        Événements émis:
        ${this.formatEvents(receipt.logs)}
      `;
    } catch (error) {
      console.error('Error generating explanation:', error);
      return 'Désolé, une erreur est survenue lors de la génération de l\'explication.';
    }
  }

  @CreateAction({
    name: "update_user_progress",
    description: "Updates user XP and level based on their actions",
    schema: UpdateUserProgressSchema
  })
  async updateUserProgress(args: z.infer<typeof UpdateUserProgressSchema>): Promise<UserProgress> {
    const { userAddress, action, context } = args;
    const userProgress = await this.getUserProgress(userAddress);
    
    // Calc earned xp
    const xpGained = this.calculateXPGain(action, context);
    
    // Update xp and lvl
    userProgress.xp += xpGained;
    userProgress.transactionsAnalyzed += 1;
    
    // Check level up
    const newLevel = this.calculateLevel(userProgress.xp);
    const leveledUp = newLevel > userProgress.level;
    userProgress.level = newLevel;

    // Check achievements
    const newAchievements = await this.checkAchievements(userProgress, context);
    userProgress.achievements.push(...newAchievements);

    // Save user progress
    await this.saveUserProgress(userProgress);

    return userProgress;
  }

  private async saveUserProgress(progress: UserProgress): Promise<void> {
    await fetch(`${this.apiUrl}/progress`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey
      },
      body: JSON.stringify(progress)
    });
  }

  private async getUserProgress(address: string): Promise<UserProgress> {
    const response = await fetch(`${this.apiUrl}/progress/${address}`, {
      headers: {
        'x-api-key': this.apiKey
      }
    });
    return response.json();
  }

  private calculateXPGain(action: string, context?: any): number {
    const xpEvent = this.XP_ACTIONS[action];
    if (!xpEvent) return 0;

    let multiplier = xpEvent.multiplier;

    // Complexity bonus
    if (context?.complexity) {
      multiplier *= (1 + context.complexity / 10);
    }

    return Math.floor(xpEvent.baseXP * multiplier);
  }

  private calculateLevel(xp: number): number {
    let level = 1;
    while (level < this.LEVEL_THRESHOLDS.getMaxLevel()) {
      const requiredXP = this.LEVEL_THRESHOLDS.calculateXPForLevel(level + 1);
      if (xp < requiredXP) break;
      level++;
    }
    return level;
  }

  private async checkAchievements(progress: UserProgress, context?: any): Promise<Achievement[]> {
    const newAchievements: Achievement[] = [];

    // Achievement example
    if (progress.transactionsAnalyzed === 1) {
      newAchievements.push({
        id: 'FIRST_ANALYSIS',
        name: 'First Steps',
        description: 'Analyzed your first transaction',
        xpReward: 100,
        dateUnlocked: Date.now()
      });
    }

    // TODO: add others achievements conditions here

    return newAchievements;
  }

  private async calculateTransactionComplexity(txHash: string): Promise<number> {
    const tx = await this.provider.getTransaction(txHash);
    let complexity = 0;
    
    if (tx) {
      // Data complexity
      complexity += tx.data && tx.data !== '0x' ? 2 : 0;
      // Value complexity
      complexity += tx.value > ethers.parseEther('1') ? 2 : 1;
      // Gas complexity
      complexity += tx.gasLimit > ethers.parseUnits('100000', 'wei') ? 2 : 1;
    }

    return complexity;
  }

}

export const transactionAnalysisProvider = (config: Partial<TransactionConfig> = {}) => {
  const defaultConfig: TransactionConfig = {
    basescanApiKey: process.env.BASESCAN_API_KEY || '',
    rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
    apiUrl: process.env.BACKEND_API_URL,
    apiKey: process.env.BACKEND_API_KEY,
    supportedNetworks: [{
      protocolFamily: 'base',
      networkId: 'base-mainnet',
      chainId: '8453'
    }]
  };

  return new TransactionAnalysisProvider({
    ...defaultConfig,
    ...config
  });
};