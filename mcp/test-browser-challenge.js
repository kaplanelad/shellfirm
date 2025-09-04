#!/usr/bin/env node

/**
 * Test script for the browser challenge system (CommonJS)
 */

const { BrowserChallenge } = require('./lib/browser-challenge.js');
const { validateSplitCommandWithOptions } = require('./lib/shellfirm-wasm.js');

async function testMathChallenge() {
  console.log('\n🧮 Testing Math Challenge...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const challengeData = {
    command: 'rm -rf * && iptables -F && ufw disable',
    patterns: ['file deletion', 'recursive removal'],
    severity: 'critical',
    matches: [
      { id: 'fs_recursive_delete', severity: 'critical', description: 'Recursive file deletion (*, -rf)' },
      { id: 'network_firewall_flush', severity: 'high', description: 'Flush firewall rules (iptables -F)' },
      { id: 'ufw_disable', severity: 'high', description: 'Disable UFW firewall' }
    ]
  };

  // Print WASM validation result for the command
  const wasmResult = await validateSplitCommandWithOptions(challengeData.command);
  console.log('WASM Validation Result:', wasmResult);

  const result = await BrowserChallenge.showChallenge('math', challengeData, 30000);

  console.log('Math Challenge Result:', result);
  return result;
}

async function testWordChallenge() {
  console.log('\n🔤 Testing Word Challenge...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const challengeData = {
    command: 'sudo chmod 777 /etc/passwd',
    patterns: ['permission change', 'system file modification'],
    severity: 'high',
    matches: [
      { id: 'chmod_world_writable', severity: 'high', description: 'Sets world-writable permissions (777)' },
      { id: 'system_file_modify', severity: 'high', description: 'Modifies critical system file (/etc/passwd)' }
    ]
  };

  // Print WASM validation result for the command
  const wasmResult = await validateSplitCommandWithOptions(challengeData.command);
  console.log('WASM Validation Result:', wasmResult);

  const result = await BrowserChallenge.showChallenge('word', challengeData, 30000);

  console.log('Word Challenge Result:', result);
  return result;
}

async function testConfirmChallenge() {
  console.log('\n⚠️ Testing Confirm Challenge...');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  const challengeData = {
    command: 'iptables -F && ufw disable',
    patterns: ['firewall disable', 'network security'],
    severity: 'medium',
    matches: [
      { id: 'network_firewall_flush', severity: 'high', description: 'Flush firewall rules (iptables -F)' },
      { id: 'ufw_disable', severity: 'high', description: 'Disable UFW firewall' }
    ]
  };

  // Print WASM validation result for the command
  const wasmResult = await validateSplitCommandWithOptions(challengeData.command);
  console.log('WASM Validation Result:', wasmResult);

  const result = await BrowserChallenge.showChallenge('confirm', challengeData, 30000);

  console.log('Confirm Challenge Result:', result);
  return result;
}



async function runAllTests() {
  console.log('🚀 Browser Challenge System Test Suite');
  console.log('═══════════════════════════════════════════════');
  console.log('Testing browser-based security challenges...');
  console.log('');
  console.log('Each test will open a browser window with a different');
  console.log('type of security challenge. Complete or close the');
  console.log('challenge to see the results.');

  const results = [];

  try {
    // Test each challenge type
    results.push(await testMathChallenge());
    results.push(await testWordChallenge());
    results.push(await testConfirmChallenge());
    // 'enter' challenge removed
    // 'yes' challenge removed

    // Summary
    console.log('\n📊 Test Summary');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    results.forEach((result, index) => {
      const types = ['Math', 'Word', 'Confirm'];
      const status = result.approved ? '✅ APPROVED' : '❌ DENIED';
      console.log(`${types[index]} Challenge: ${status}`);
      if (result.error) {
        console.log(`  Error: ${result.error}`);
      }
    });

    const approvedCount = results.filter(r => r.approved).length;
    console.log(`\nTotal: ${approvedCount}/${results.length} challenges approved`);

  } catch (error) {
    console.error('Test suite error:', error);
  }

  console.log('\n🎉 Browser Challenge Test Complete!');
}

// Parse command line arguments
const args = process.argv.slice(2);
const challengeType = args[0];

if (challengeType === 'math') {
  testMathChallenge().catch(console.error);
} else if (challengeType === 'word') {
  testWordChallenge().catch(console.error);
} else if (challengeType === 'confirm') {
  testConfirmChallenge().catch(console.error);
} else {
  // Run all tests by default
  runAllTests().catch(console.error);
}
