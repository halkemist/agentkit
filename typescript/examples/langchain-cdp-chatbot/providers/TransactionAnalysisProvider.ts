import { z } from "zod";
import { CreateAction } from "@coinbase/agentkit";
import { ActionProvider } from "@coinbase/agentkit";
import { Network } from "@coinbase/agentkit";
import { ethers } from 'ethers';

// Types
interface TransactionRisk {
  riskLevel: 'safe' | 'warning' | 'danger';
  reason: string;
  recommendation: string;
}

interface TransactionMetrics {
  uniqueContracts: number;
  defiInteractions: number;
  successRate: number;
  complexityScore: number;
}

interface ProgressMetrics extends TransactionMetrics {
  totalTransactions: number;
  averageGasUsed: string;
}

interface TransactionConfig {
  basescanApiKey: string;
  rpcUrl: string;
  scamDatabaseUrl?: string;
  supportedNetworks?: string[];
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

const AssessLevelProgressSchema = z.object({
  userAddress: z.string(),
  currentLevel: z.number().min(1).max(100),
  recentTransactions: z.array(z.object({
    hash: z.string(),
    to: z.string(),
    from: z.string(),
    value: z.string(),
    data: z.string(),
    status: z.boolean(),
    gasUsed: z.string()
  }))
});

/**
 * TransactionAnalysisProvider to analyse transactions
 */
export class TransactionAnalysisProvider extends ActionProvider {
  private lastKnownTx: Record<string, string>;
  private readonly basescanApiKey: string;
  private readonly provider: ethers.JsonRpcProvider(config.rpcUrl);
  private readonly scamDatabaseUrl?: string;
  private readonly supportedNetworks: string[];

  constructor(config: TransactionConfig) {
    super("enhanced_transaction_analysis", []);
    this.lastKnownTx = {};
    this.basescanApiKey = config.basescanApiKey;
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.scamDatabaseUrl = config.scamDatabaseUrl;
    this.supportedNetworks = config.supportedNetworks || ['base-mainnet', 'base-goerli'];
    this.rpcUrl = config.rpcUrl;
  }

  supportsNetwork(networkId: Network): boolean {
    return this.supportedNetworks.includes(networkId);
  }

  private async getLatestTransaction(address: string): Promise<ethers.TransactionResponse | null> {
    try {
      const history = await this.provider.getHistory(address);
      return history.length > 0 ? history[0] : null;
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

  private async checkAgainstScamDatabase(address: string): Promise<boolean> {
    if (!this.scamDatabaseUrl) return false;
    try {
      const response = await fetch(`${this.scamDatabaseUrl}/${address}`);
      const data = await response.json();
      return data.isScam || false;
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

  private formatEvents(logs: ethers.Log[]): string {
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

  private calculateComplexityScore(transactions: z.infer<typeof AssessLevelProgressSchema>['recentTransactions']): number {
    return transactions.reduce((score, tx) => {
      score += tx.data !== '0x' ? 2 : 1; // Contract interactions worth more
      score += Number(tx.value) > 0 ? 1 : 0; // Value transfers add points
      return score;
    }, 0);
  }

  private calculateProgressPercentage(metrics: TransactionMetrics): number {
    const maxScore = 100;
    const currentScore = (
      (metrics.uniqueContracts * 10) +
      (metrics.defiInteractions * 15) +
      (metrics.successRate * 25) +
      (metrics.complexityScore * 5)
    );
    return Math.min(Math.round((currentScore / maxScore) * 100), 100);
  }

  private generateLevelUpReason(metrics: ProgressMetrics): string {
    const reasons: string[] = [];
    
    if (metrics.uniqueContracts > 5) 
      reasons.push('Diverse contract interactions');
    if (metrics.defiInteractions > 10) 
      reasons.push('Active DeFi participation');
    if (metrics.successRate > 0.9) 
      reasons.push('High transaction success rate');
    if (metrics.complexityScore > 50) 
      reasons.push('Complex transaction handling');

    return reasons.join(', ');
  }

  private async assessTransactionRisk(
    tx: ethers.TransactionResponse,
    receipt: ethers.TransactionReceipt
  ): Promise<TransactionRisk> {
    try {
      // Convertir la valeur en ETH pour une meilleure lisibilité
      const valueInEth = Number(ethers.formatEther(tx.value));
      const gasUsed = receipt.gasUsed;
      const gasLimit = tx.gasLimit;
  
      // Facteurs de risque
      const riskFactors = {
        highValue: valueInEth > 1, // Transaction > 1 ETH
        unusualGas: gasUsed > (gasLimit * BigInt(8)) / BigInt(10), // Utilisation de plus de 80% du gas limit
        newContract: tx.to ? !(await this.isVerifiedContract(tx.to)) : true,
        knownScam: tx.to ? await this.checkAgainstScamDatabase(tx.to) : false,
        failedTx: receipt.status === 0,
        complexData: tx.data && tx.data.length > 138, // Data complexe (plus que simple transfer)
        highGasPrice: tx.gasPrice > ethers.parseUnits("100", "gwei") // Gas price > 100 gwei
      };
  
      // Analyse des risques critiques
      if (riskFactors.knownScam) {
        return {
          riskLevel: 'danger',
          reason: '🚨 Cette adresse est signalée comme malveillante dans notre base de données!',
          recommendation: 'Annulez immédiatement toute transaction avec cette adresse et signalez-la à votre communauté.'
        };
      }
  
      if (riskFactors.failedTx) {
        return {
          riskLevel: 'warning',
          reason: '⚠️ La transaction a échoué',
          recommendation: 'Vérifiez les paramètres de la transaction et le solde de votre compte avant de réessayer.'
        };
      }
  
      // Analyse des risques combinés
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
  
      // Transaction standard
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
  
      // Niveau débutant (1-20)
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
  
      // Niveau intermédiaire (21-60)
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
  
      // Niveau avancé (61-100)
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

}

export const transactionAnalysisProvider = (config: Partial<TransactionConfig> = {}) => {
  const defaultConfig: TransactionConfig = {
    basescanApiKey: process.env.BASESCAN_API_KEY || '',
    rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
    scamDatabaseUrl: process.env.SCAM_DATABASE_URL,
    supportedNetworks: ['base-mainnet', 'base-goerli']
  };

  return new TransactionAnalysisProvider({
    ...defaultConfig,
    ...config
  });
};