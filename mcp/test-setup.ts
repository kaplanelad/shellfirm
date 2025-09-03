// Test setup for Vitest
import { beforeAll, afterAll } from 'vitest';

// Global test setup
beforeAll(async () => {
  console.log('🧪 Setting up test environment...');
});

afterAll(async () => {
  console.log('🧹 Cleaning up test environment...');
});
