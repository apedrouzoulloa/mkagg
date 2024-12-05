## Overview

This repository contains a report and the code used to evaluate the performance of the protocol presented in:

Alberto Pedrouzo-Ulloa, Aymen Boudguiga, Olive Chakraborty, Renaud Sirdey, Oana Stan, Martin Zuber:
Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation. CSR 2023: 612-617.

The repository includes:
1. Implementations of the protocol, with and without parallelization.
2. A baseline BFV implementation for comparison.
3. A detailed report in PDF format, including a summary of the original work, a discussion parameter selection and tables with execution runtimes.

## Structure
- `docs/`: Contains technical documents and presentations related to the project.
- `mkAgg-sequential/`: Sequential implementation of the protocol.
- `mkAgg-parallel/`: Parallel implementation of the protocol using Go routines.
- `BFVbaselineAgg/`: Reference implementation using the BFV scheme.

## Contact

To contact us, please send an email to: [apedrouzo@gts.uvigo.es](mailto:apedrouzo@gts.uvigo.es).

## Citation

Please use the following BibTex entry to cite our work:

  @inproceedings{PBCSSZ23,
      author = {Alberto Pedrouzo{-}Ulloa and Aymen Boudguiga and Olive Chakraborty and Renaud Sirdey and Oana Stan and Martin Zuber},
      title = {Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation},
      booktitle = {{IEEE} International Conference on Cyber Security and Resilience, {CSR} 2023, Venice, Italy, July 31 - Aug. 2, 2023},
      pages = {612--617},
      publisher = {{IEEE}},
      year = {2023}
  }

## References
1. Alberto Pedrouzo-Ulloa, Aymen Boudguiga, Olive Chakraborty, Renaud Sirdey, Oana Stan, Martin Zuber: Practical Multi-Key Homomorphic Encryption for More Flexible and Efficient Secure Federated Average Aggregation. CSR 2023: 612-617.

## Dependencies
This project uses the Lattigo v5 library, an open-source library for homomorphic encryption.

## License

This project is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0). See the `LICENSE` file for more details.

Additionally, this project uses the Lattigo v5 library, which is also licensed under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0). 
A copy of Lattigo's license is included in the file `LICENSE.Lattigo`. Please refer to it for more information.

