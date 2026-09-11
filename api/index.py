import sys
import os

# Add parent project root directory to Python path for Vercel Serverless Function
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import app
