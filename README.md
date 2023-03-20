# TFHE-rs-Applications
Optimize and benchmark applications using TFHE-rs FHE library. These applications demonstrate various use cases and specific optimizations to improve FHE performance.

The library in use is [GitHub - zama-ai/tfhe-rs: TFHE-rs: Pure Rust implementation of the TFHE scheme for boolean and integers FHE arithmetics.](https://github.com/zama-ai/tfhe-rs).
The TFHE-rs API is a powerful tool for performing homomorphic encryption in Rust.

If you're interested in homomorphic encryption and want to explore optimizations and various calculation implementations using the TFHE-rs library, this repository provides a collection of applications that can help.

## Introduction:
The aim of this repository is to contain several applications designed to help better understand and optimize the performance of FHE code. 

## Applications:
Included in this repository are some applications that demonstrate different use cases for TFHE-rs, as well as benchmarking and optimization techniques. These applications include:

    [MultiBit Lower-Than]: Take advantage of TFHE-rs programmable bootstrapping (PBS) API. Rely more on PBS than simple algebra homomorphic operations.
    [Cardio Risk Calculation]: Rely on PBS to reduce comparisons cost.

## Optimization and Benchmarking:
Optimization and benchmarking are critical for achieving optimal performance with FHE. These applications provide a platform for exploring different optimization techniques and measuring the impact of those optimizations on performance.

Specific optimizations that these applications are designed to test or explore include usage of PBS wherever possible, manually optimize operations whenever possible, choose the best performing API calls depending on the need/context.

## Limitations and Features:
It's important to note that the TFHE-rs API is still in development and any new release can, and probably will, affect performance and compilation of these applications.
