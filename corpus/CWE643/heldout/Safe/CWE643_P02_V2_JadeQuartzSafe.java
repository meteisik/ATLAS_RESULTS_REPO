import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P02_V2_JadeQuartzSafe {
    private static int privateFive = 5;

    public void runJadeQuartz() throws XPathExpressionException {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeQuartzXmlFile = null;
            if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
                jadeQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
            } else {
                jadeQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
            }
            if (data != null) {
                String[] jadeQuartzTokens = data.split("||");
                if (jadeQuartzTokens.length < 2) {
                    return;
                }
                String jadeQuartzUser = jadeQuartzTokens[0];
                String jadeQuartzPass = jadeQuartzTokens[1];
                XPath jadeQuartzXPath = XPathFactory.newInstance().newXPath();
                InputSource jadeQuartzXml = new InputSource(jadeQuartzXmlFile);
                String jadeQuartzQuery = "//users/user[name/text()='" + jadeQuartzUser
                        + "' and pass/text()='" + jadeQuartzPass + "']" + "/secret/text()";
                String jadeQuartzSecret = (String) jadeQuartzXPath.evaluate(jadeQuartzQuery, jadeQuartzXml, XPathConstants.STRING);
                System.out.println(jadeQuartzSecret);
            }
        }
    }
}
