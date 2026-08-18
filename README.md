# \# 🛡️ PhishGuard AI

# 

# \## AI-Powered Phishing Email Detection System

# 

# PhishGuard AI is a machine-learning-based web application designed to detect potential phishing emails.

# 

# The system analyzes the sender email, subject, and email content and provides a risk assessment. It displays the risk score, risk level, phishing probability, legitimate probability, detection findings, and detected URLs.

# 

# \---

# 

# \## 🎯 Project Objective

# 

# The main objective of PhishGuard AI is to help users identify suspicious emails before interacting with potentially dangerous links or providing sensitive information.

# 

# The application combines a machine learning model with a Flask backend and a modern web interface to provide an easy-to-understand phishing risk assessment.

# 

# \---

# 

# \## ✨ Features

# 

# \- 🤖 Machine Learning-based phishing detection

# \- 📧 Sender email analysis

# \- 📝 Subject analysis

# \- 🔎 Email content analysis

# \- 🔗 URL detection

# \- ⚠️ Risk level detection

# \- 📊 Risk score percentage

# \- 🎣 Phishing probability

# \- 🛡️ Legitimate probability

# \- 🔍 Detection findings

# \- 🎨 Modern responsive user interface

# \- ⚡ Flask REST API backend

# \- 💻 Local email analysis

# 

# \---

# 

# \## 🧠 How It Works

# 

# ```text

# User enters email

# &#x20;       ↓

# Frontend

# &#x20;       ↓

# Flask REST API

# &#x20;       ↓

# Machine Learning Model

# &#x20;       ↓

# Email Prediction

# &#x20;       ↓

# Risk Score Calculation

# &#x20;       ↓

# Detection Findings

# &#x20;       ↓

Result displayed to UserAi--Phishing--Detection
🏗️ Project Structure
===

# AI-Phishing-Detection/

# │

# ├── backend/

# │   └── app.py

# │

# ├── frontend/

# │   └── index.html

# │

# ├── model/

# │   └── trained model files

# │

# ├── data/

# │   └── dataset files

# │

# ├── requirements.txt

# ├── .gitignore

# └── README.md

# 🛠️ Technologies Used

# Frontend

# HTML5

# CSS3

# JavaScript

# Backend

# Python

# Flask

# REST API

# Machine Learning

# Scikit-learn

# NumPy

# Pandas

# SciPy

# Development Tools

# Visual Studio Code

# Git

# GitHub

# 📊 Detection Results

# 

# PhishGuard AI provides the following information after analyzing an email:

# 

# Result	Description

# Risk Score	Overall estimated risk percentage

# Risk Level	LOW, MEDIUM, HIGH or CRITICAL

# Phishing Probability	Estimated probability of phishing

# Legitimate Probability	Estimated probability of being legitimate

# Detection Findings	Suspicious indicators identified

# Detected URLs	URLs found in the email

# 🧪 Testing

# 

# The application was tested using different types of emails.

# 

# High-Risk Email

# 

# Suspicious emails containing indicators such as:

# 

# Urgent account warnings

# Requests for passwords

# Suspicious links

# Account verification requests

# Threatening language

# 

# The system successfully identified tested phishing examples as HIGH RISK.

# 

# Low-Risk Email

# 

# Normal emails containing:

# 

# Regular communication

# Class or work notifications

# Non-suspicious content

# No obvious malicious requests

# 

# The system successfully identified tested legitimate examples as LOW RISK.

