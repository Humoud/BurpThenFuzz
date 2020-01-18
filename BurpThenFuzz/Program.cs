using System;
using System.Net;
using System.IO;
using System.Xml;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;


namespace BurpThenFuzz
{
    class Program
    {
        // TODO: ADD SCOPE <POC DONE>
        // TODO: Modify XML doc version, first line from 1.1 to 1.0 <DONE>
        // TODO: ADD STATISTICS AND ANALYTICS
        // TODO: HANDLE GET REQUESTS <POC DONE>
        // TODO: HANDLE POST REQUESTS, taken in request base64 encoded to be able to check for duplicates <POC DONE>
        // TODO: Pass Through a Proxy <POC DONE>
        // TODO: Analyze Parameters
        // TODO: Handle other HTTP Methods
        public static string proxyIP;
        public static int proxyPort;
        // nodes which contain GET requests
        public static List<XmlNode> urlsGET;
        // nodes which contain POST requests
        public static List<XmlNode> urlsPOST;
        static void Main(string[] args)
        {
            // burpToFuzz target_host xml_doc_path proxy_ip proxy_port
            string scope = args[0];
            string xmlDocPath = args[1];
            proxyIP = args[2];
            proxyPort = Convert.ToInt32(args[3]);
            urlsGET = new List<XmlNode>();
            urlsPOST = new List<XmlNode>();

            Console.WriteLine("=====\nScope: {0}\nBurp XML File: {1}\n=====", scope, xmlDocPath);
            //// .Net does not support XML 1.1
            //// Here We are overwriting the first line of the XML file
            //// To Modify the version
            // https://stackoverflow.com/questions/29987169/c-sharp-overwrite-first-few-lines-of-a-text-file-with-constant-time
            // Note: reading all lines might cause memory issues
            string[] lines = System.IO.File.ReadAllLines(xmlDocPath);
            lines[0] = "<?xml version=\"1.0\"?>";
            System.IO.File.WriteAllLines(xmlDocPath, lines);
            XmlDocument doc = new XmlDocument();
            doc.Load(xmlDocPath);
            lines = null;
            foreach (XmlNode node in doc.DocumentElement.ChildNodes)
            {
                XmlNode urlNode = node.SelectSingleNode("url");
                XmlNode hostNode = node.SelectSingleNode("host");
                XmlNode methodNode = node.SelectSingleNode("method");

                // If request is not in scope then skip this iteration
                if (hostNode.InnerText != scope)
                    continue;

                // Process GET request nodes
                if(methodNode.InnerText == "GET")
                {
                    // if the URL contains a GET parameter
                    if (urlNode.InnerText.Contains('?'))
                    {
                        // check for duplicates
                        var match = urlsGET.FirstOrDefault(
                        getReqNode =>
                            getReqNode.SelectSingleNode("url").InnerText == urlNode.InnerText
                        );
                        // if new entry
                        if (match == null)
                        {
                            Console.WriteLine("New Entry!");
                            Console.WriteLine("Testing <GET>: " + urlNode.InnerText);
                            urlsGET.Add(node);
                            HandleGetRequest(node);
                        }
                    }
                }
                // Process POST request nodes
                else if (methodNode.InnerText == "POST")
                {
                    XmlNode request = node.SelectSingleNode("request");
                    // check for duplicates
                    var match = urlsPOST.FirstOrDefault(
                        postReqNode =>
                            postReqNode.SelectSingleNode("request").InnerText == request.InnerText
                    );
                    // if new entry
                    if (match == null)
                    {
                        Console.WriteLine("New Entry!");
                        Console.WriteLine("Testing <POST>: " + urlNode.InnerText);
                        urlsPOST.Add(node);
                        HandlePOSTRequest(node);
                    }
                }
            }
        }

        private static void HandlePOSTRequest(XmlNode node)
        {
            //string host = node.SelectSingleNode("host").InnerText;
            //int port = Convert.ToInt32(node.SelectSingleNode("port").InnerText);
            //IPEndPoint rhost = new IPEndPoint(IPAddress.Parse(host), port);



            XmlNode requestNode = node.SelectSingleNode("request");
            // Decode and split at new lines, so that we can
            // get the last line of the request which contains the
            // POST params
            byte[] data = Convert.FromBase64String(requestNode.InnerText);
            string decodedRequest = Encoding.UTF8.GetString(data);
            string[] decodedRequestLines = decodedRequest.Split("\n");
            string[] parms = decodedRequestLines[decodedRequestLines.Length - 1].Split("&");

            foreach (string p in parms)
            {
                WebRequest request = WebRequest.Create(node.SelectSingleNode("url").InnerText);
                request.Proxy = new WebProxy(proxyIP, proxyPort); request.Proxy = new WebProxy(proxyIP, proxyPort);
                request.Method = "POST";
                // extract headers from request and use them to build a new request
                ArraySegment<String> headerLines = new ArraySegment<String>(decodedRequestLines, 1, decodedRequestLines.Length - 3);
                foreach (string head in headerLines)
                {
                    string[] keyval = head.Split(":");
                    request.Headers.Add(keyval[0], string.Join(":", keyval[1..keyval.Length]));
                }
                string val = p.Split('=')[1];
                string postReqData = decodedRequestLines[decodedRequestLines.Length - 1].Replace("=" + val, "=" + val + "'");
                byte[] byteArray = Encoding.UTF8.GetBytes(postReqData);
                request.ContentLength = byteArray.Length;
                // Get the request stream.
                Stream dataStream = request.GetRequestStream();
                // Write the data to the request stream.  
                dataStream.Write(byteArray, 0, byteArray.Length);
                // Close the Stream object.  
                dataStream.Close();
                // Get the response.  
                WebResponse response = request.GetResponse();
                // Display the status.  
                //Console.WriteLine(((HttpWebResponse)response).StatusDescription);

                // Get the stream containing content returned by the server.  
                // The using block ensures the stream is automatically closed.
                using (dataStream = response.GetResponseStream())
                {
                    // Open the stream using a StreamReader for easy access.  
                    StreamReader reader = new StreamReader(dataStream);
                    // Read the content.  
                    string responseFromServer = reader.ReadToEnd();
                    // Display the content.
                    if (responseFromServer.Contains("error in your SQL syntax"))
                        Console.WriteLine("Parameter " + p + " seems vulnerable to SQL injection with value: " + val + "'");

                }

                // Close the response.  
                response.Close();
            }
        }

        // Parse GET parameters
        // Fuzzes the GET paremeters
        // issues the actual Fuzzed GET requests
        // analyzes the response received
        // XmlNode node: node which contains a GET request
        private static void HandleGetRequest(XmlNode node)
        {
            XmlNode urlNode = node.SelectSingleNode("url");
            string url = urlNode.InnerText;

            string[] getParams = url.Remove(0, url.IndexOf("?") + 1).Split('&');

            foreach (string p in getParams)
            {
                string fuzzUrl = FuzzGETGenerator(url, p);
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(fuzzUrl);
                request.Proxy = new WebProxy(proxyIP, proxyPort);
                request.Method = "GET";

                string xssresp = string.Empty;
                // initiate GET request <FUZZ>:
                try
                {
                    using (StreamReader rdr = new
                        StreamReader(request.GetResponse().GetResponseStream()))
                    {
                        xssresp = rdr.ReadToEnd();
                    }
                    if (xssresp.Contains("<fuzz>"))
                    {
                        Console.WriteLine("> Possible XSS point found in parameter: " + p);
                    }
                }
                catch (WebException wex)
                {
                    if (wex.Response != null)
                    {
                        using (var errorResponse = (HttpWebResponse)wex.Response)
                        {
                            using (var reader = new StreamReader(errorResponse.GetResponseStream()))
                            {
                                string error = reader.ReadToEnd();
                                Console.WriteLine("=======\nError:\n\n{0}=======\n", error);
                                //TODO: use JSON.net to parse this string and look at the error message
                            }
                        }
                    }
                }
            }
        }

        private static string FuzzGETGenerator(string url, string parameter)
        {
            string xssUrl = url.Replace(parameter, parameter + "test<fuzz>");
            return xssUrl;
        }
    }
}
