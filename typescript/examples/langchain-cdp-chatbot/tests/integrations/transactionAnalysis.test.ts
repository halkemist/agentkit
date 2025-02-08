import { transactionAnalysisProvider } from "../../providers/TransactionAnalysisProvider";
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import dotenv from 'dotenv';
import { ethers } from 'ethers';

dotenv.config();

async function testOpenAIConnection() {
  console.log('Testing OpenAI connection...');
  const testLlm = new ChatOpenAI({
    modelName: "gpt-3.5-turbo",
    temperature: 0.7,
    openAIApiKey: process.env.OPENAI_API_KEY
  });

  try {
    const response = await testLlm.invoke("Say hello");
    console.log('OpenAI test response:', response);
    return true;
  } catch (error) {
    console.error('OpenAI test failed:', error);
    return false;
  }
}

// Helper pour obtenir une transaction récente
async function getRecentTransaction() {
  const provider = new ethers.JsonRpcProvider(process.env.BASE_RPC_URL);
  const latestBlock = await provider.getBlock('latest');
  if (!latestBlock) throw new Error('Could not fetch latest block');
  
  // Prendre la première transaction du dernier block
  const txHash = latestBlock.transactions[0];
  return txHash;
}

async function testAnalysis() {
  console.log('Starting transaction analysis test...');

  // Test OpenAI first
  const openAIWorks = await testOpenAIConnection();
  if (!openAIWorks) {
    console.error('OpenAI connection failed, stopping tests');
    return;
  }

  // 1. Initialiser le LLM
  const llm = new ChatOpenAI({
    modelName: "gpt-3.5-turbo",
    temperature: 0.7,
    maxRetries: 5,
    maxConcurrency: 1
  });

  // 2. Créer l'agent React
  const agent = createReactAgent({
    llm,
    tools: [], // Pas besoin d'outils supplémentaires pour ce test
    messageModifier: `
      You are a blockchain transaction analysis expert. Analyze the transaction data and provide insights 
      based on the user's expertise level. Use technical terms for high levels and simple explanations for beginners.
    `
  });

  // 3. Initialiser le provider
  const provider = transactionAnalysisProvider({
    basescanApiKey: process.env.BASESCAN_API_KEY,
    rpcUrl: process.env.BASE_RPC_URL,
    apiUrl: 'http://localhost:3000',
    apiKey: process.env.BACKEND_API_KEY
  });

  // 4. Important: Définir l'agent complet
  provider.setAgent(agent);

  try {
    // 5. Obtenir une transaction récente
    const txHash = await getRecentTransaction();
    console.log(`\nTesting with transaction: ${txHash}`);

    // 6. Tester les différents niveaux d'utilisateur
    const userLevels = [1, 30, 80]; // Débutant, Intermédiaire, Avancé
    
    for (const level of userLevels) {
      console.log(`\n📊 Testing analysis for user level ${level}:`);
      console.log('----------------------------------------');
      
      const analysis = await provider.analyzeTransaction({
        txHash,
        userLevel: level,
        isNewTransaction: true
      });

      console.log(analysis);
      
      // Petite pause entre les tests
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // 7. Tester le cache
    console.log('\n🔄 Testing cached response:');
    console.log('----------------------------------------');
    const cachedAnalysis = await provider.analyzeTransaction({
      txHash,
      userLevel: 1,
      isNewTransaction: false
    });
    console.log(cachedAnalysis);

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Exécuter les tests
console.log('🚀 Starting tests...');
testAnalysis()
  .then(() => console.log('\n✅ Tests completed'))
  .catch(error => console.error('\n❌ Tests failed:', error))
  .finally(() => process.exit());