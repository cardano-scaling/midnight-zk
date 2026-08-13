import { createHashRouter, RouterProvider } from "react-router-dom";
import ExamplePicker from "./components/ExamplePicker";
import Shell from "./components/Shell";
import TableView from "./components/table/TableView";
import DomainView from "./components/domain/DomainView";
import ProverView from "./components/prover/ProverView";
import VerifierView from "./components/verifier/VerifierView";

const router = createHashRouter([
  { path: "/", element: <ExamplePicker /> },
  {
    path: "/:example",
    element: <Shell />,
    children: [
      { index: true, element: <TableView /> },
      { path: "table", element: <TableView /> },
      { path: "domain", element: <DomainView /> },
      { path: "prover", element: <ProverView /> },
      { path: "verifier", element: <VerifierView /> },
    ],
  },
]);

export default function App() {
  return <RouterProvider router={router} />;
}
