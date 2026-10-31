# Image transfer demo samples

Original JPEG downloads from NASA, provided for local SPARC demonstrations.
The files retain the downloaded bytes; they are not AI-generated or re-encoded.

| File | Source and credit | Demo use |
| --- | --- | --- |
| `earth-blue-marble.jpg` | [Blue Marble 2002](https://science.nasa.gov/resource/blue-marble-2002/) — NASA's Earth Observatory | Small color image for a quick transfer |
| `moon.jpg` | [Earth's Moon](https://science.nasa.gov/resource/earths-moon/) — NASA/JPL/USGS | Detailed lunar texture |
| `mars-collage.jpg` | [HiRISE's Mars Collage](https://science.nasa.gov/resource/hirises-mars-collage/) — NASA/JPL-Caltech/University of Arizona | Larger image for observing chunked transfer traffic |

See [NASA's media usage guidelines](https://www.nasa.gov/nasa-brand-center/images-and-media/).
NASA does not endorse SPARC.

From the repository root, copy the samples to running Docker peers without
restarting their windows:

```sh
docker compose cp demo-images/. alice:/data/demo-images
docker compose cp demo-images/. bob:/data/demo-images
```

In either peer, choose **Chat → Attach image**, enter `/data/demo-images/` in
the file chooser's directory field, select a JPEG, then click **Send image**.
Connect and approve the peers first. Accept the image on the receiving side
when prompted. The samples live in each peer's persistent data volume.
