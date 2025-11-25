<p align="center">
  <h1 align="center">
  FlowScan
  </h1>
</p>

<p align="center">
  FlowScan is a modular security scanner designed for AI workflows and agents.
</p>

<div align="center">
  <img src="https://github.com/Antimony5292/img/blob/main/FlowScan_example.png" alt="logo"/>
</div>



## 🚀 Features

- Multi-Platform Support: Currently supports n8n (.json) workflows.

- Secret Detection: Scans for hardcoded API keys, passwords, tokens, and other sensitive data.

- Risk Analysis: Identifies potential prompt injection risks in AI and HTTP nodes.

- Visual Reports: Generates a clean, interactive HTML report (report.html) for easy sharing.

- Modular Architecture: Easily extensible to support new platforms and rule sets.

## 📦 Installation

```bash
git clone https://github.com/yourusername/FlowScan.git
cd FlowScan
```


## 🛠️ Usage

Run the scanner by pointing it to a specific file or a directory containing your workflows.

**Basic Scan**

Scan a folder of workflows and generate a report:

```bash
python run.py ./my_workflows
```

**Scan a Single File**

```bash
python run.py ./my_workflows/secret_agent.json
```

**Custom Output Path**

Specify where to save the HTML report:

```bash
python run.py ./workflows -o ./security_audit.html
```


## 📝 Roadmap

We are actively working on expanding the scanner's capabilities. Planned features include:

[ ] Enhanced Dify Support

[ ] Data Mapping Validation: Detect issues where node output data types do not match expected input fields (Data Mismatch).

[ ] Data Transformation Checks: Identify potential errors in data transformation steps (e.g., incorrect regex, invalid JSON structures).

[ ] Null Value Detection: Scan for critical fields that are left empty or null unexpectedly.

[ ] Anomaly Detection: Flag abnormal data patterns or outlier configurations in workflow parameters.

## 🤝 Contributing

Contributions are welcome! We also welcome suggestions, bug reports, or feature requests as GitHub issues.

## 🎯 Resources

Here are some existing Workflow repositories.

- [awesome-n8n-templates](https://github.com/enescingoz/awesome-n8n-templates) by enescingoz

- [n8n-workflows](https://github.com/Zie619/n8n-workflows) by Zie619

- [n8n-free-templates](https://github.com/wassupjay/n8n-free-templates) by wassupjay

- [Awesome-Dify-Workflow](https://github.com/svcvit/Awesome-Dify-Workflow) by svcvit