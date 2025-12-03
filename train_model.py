#!/usr/bin/env python3
"""
Training script for SQL Injection Detection Model
Creates sample training data and trains the ML model
"""

import sys
import os
import pandas as pd
import numpy as np
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sql_prevention_project.core.detector import SQLPreventionproject
from sql_injection_detector.utils.logger import get_logger

logger = get_logger(__name__)

def create_sample_training_data():
    """Create comprehensive sample training data"""
    
    # Benign queries
    benign_queries = [
        "SELECT * FROM users WHERE id = 1",
        "SELECT name, email FROM customers WHERE active = 1",
        "INSERT INTO products (name, price) VALUES ('Widget', 19.99)",
        "UPDATE users SET last_login = NOW() WHERE id = 123",
        "DELETE FROM temp_data WHERE created_date < '2023-01-01'",
        "SELECT COUNT(*) FROM orders WHERE status = 'completed'",
        "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
        "SELECT * FROM products WHERE category_id IN (1, 2, 3, 4, 5)",
        "INSERT INTO logs (user_id, action, timestamp) VALUES (1, 'login', NOW())",
        "SELECT AVG(price) FROM products WHERE category = 'electronics'",
        "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 10",
        "SELECT * FROM users WHERE email LIKE '%@company.com'",
        "DELETE FROM sessions WHERE expires_at < NOW()",
        "SELECT * FROM orders WHERE total > 100 AND status = 'pending'",
        "INSERT INTO customers (name, email, phone) VALUES ('John Doe', 'john@email.com', '555-1234')",
        "SELECT * FROM products WHERE price BETWEEN 10 AND 50",
        "UPDATE users SET profile_updated = 1 WHERE id = 456",
        "SELECT DISTINCT category FROM products ORDER BY category",
        "SELECT * FROM users WHERE registration_date >= '2023-01-01'",
        "INSERT INTO audit_log (table_name, operation, user_id) VALUES ('users', 'update', 789)"
    ]
    
    # Malicious queries (SQL Injection)
    malicious_queries = [
        "SELECT * FROM users WHERE id = 1' OR '1'='1",
        "SELECT * FROM users WHERE id = 1; DROP TABLE users;--",
        "SELECT * FROM users WHERE name = 'admin' UNION SELECT password FROM admin_users--",
        "SELECT * FROM users WHERE id = 1' OR 1=1--",
        "'; DROP TABLE students; --",
        "admin'/*",
        "SELECT * FROM users WHERE id = 1' AND SLEEP(5)--",
        "SELECT * FROM users WHERE id = 1' UNION SELECT @@version--",
        "SELECT * FROM users WHERE id = 1' OR 'a'='a",
        "SELECT * FROM users WHERE id = 1' UNION ALL SELECT NULL,NULL,NULL--",
        "SELECT * FROM users WHERE id = 1' AND 1=2 UNION SELECT username,password FROM admin--",
        "SELECT * FROM products WHERE id = 1' OR EXISTS(SELECT * FROM users WHERE admin=1)--",
        "SELECT * FROM users WHERE id = 1'; INSERT INTO users (username,password) VALUES ('hacker','pass')--",
        "SELECT * FROM users WHERE id = 1' AND (SELECT COUNT(*) FROM admin) > 0--",
        "SELECT * FROM users WHERE id = 1' OR ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)) > 64--",
        "SELECT * FROM users WHERE id = 1' UNION SELECT table_name,column_name FROM information_schema.columns--",
        "SELECT * FROM users WHERE id = 1' AND BENCHMARK(1000000,SHA1('test'))--",
        "SELECT * FROM users WHERE id = 1' OR 1=1 LIMIT 1--",
        "SELECT * FROM users WHERE id = 1' UNION SELECT 1,2,3,4,5--",
        "SELECT * FROM users WHERE id = 1' AND (SELECT * FROM users WHERE username='admin' AND password LIKE 'a%')--",
        "SELECT * FROM users WHERE id = 1' OR 1=1#",
        "SELECT * FROM users WHERE id = 1' UNION SELECT null,version(),null--",
        "SELECT * FROM users WHERE id = 1' AND 1=0 UNION SELECT database(),user(),version()--",
        "SELECT * FROM users WHERE id = 1' WAITFOR DELAY '00:00:05'--",
        "SELECT * FROM users WHERE id = 1' AND 1=CAST((SELECT COUNT(*) FROM users) AS INT)--",
        "SELECT * FROM users WHERE id = 1' OR 'x'='x",
        "SELECT * FROM users WHERE id = 1' UNION SELECT CHAR(117,115,101,114,110,97,109,101),CHAR(112,97,115,115,119,111,114,100) FROM admin--",
        "SELECT * FROM users WHERE id = 1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "SELECT * FROM users WHERE id = 1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "SELECT * FROM users WHERE id = 1' OR 1=1 INTO OUTFILE '/tmp/test.txt'--"
    ]
    
    # Create DataFrame
    data = []
    
    # Add benign queries
    for query in benign_queries:
        data.append({'query': query, 'is_malicious': 0})
    
    # Add malicious queries
    for query in malicious_queries:
        data.append({'query': query, 'is_malicious': 1})
    
    df = pd.DataFrame(data)
    
    # Shuffle the data
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    logger.info(f"Created training dataset with {len(df)} samples")
    logger.info(f"Benign queries: {len(benign_queries)}")
    logger.info(f"Malicious queries: {len(malicious_queries)}")
    
    return df

def train_and_save_model():
    """Train the ML model with sample data"""
    logger.info("Starting ML model training...")
    
    # Create training data
    training_data = create_sample_training_data()
    
    # Initialize detector
    detector = SQLInjectionDetector()
    
    # Train the model
    try:
        detector.train_model(training_data)
        
        # Save the trained model
        model_path = "trained_model.pkl"
        detector.save_model(model_path)
        
        logger.info(f"Model training completed and saved to {model_path}")
        
        # Test the trained model
        test_queries = [
            "SELECT * FROM users WHERE id = 1",  # Benign
            "SELECT * FROM users WHERE id = 1' OR '1'='1",  # Malicious
        ]
        
        print("\n" + "="*80)
        print("TESTING TRAINED MODEL")
        print("="*80)
        
        for query in test_queries:
            result = detector.analyze_query(query)
            print(f"Query: {query}")
            print(f"Malicious: {result.is_malicious}")
            print(f"Confidence: {result.confidence:.3f}")
            print(f"Attack Type: {result.attack_type}")
            print(f"Risk Score: {result.risk_score:.3f}")
            print("-" * 40)
        
        return True
        
    except Exception as e:
        logger.error(f"Error during model training: {str(e)}")
        return False

if __name__ == "__main__":
    success = train_and_save_model()
    if success:
        print("\n Model training completed successfully!")
        print("You can now use the trained model for improved detection accuracy.")
    else:
        print("\n Model training failed. Please check the logs for details.")
        sys.exit(1)
