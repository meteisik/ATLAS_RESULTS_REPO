import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_JadeSignalSafe {

    public void runJadeSignal() throws XPathExpressionException {
        String data;
        data = "foo";
        (new CWE643_P06_V1_JadeSignalSafeSink()).sinkJadeSignal(data);
    }
}

class CWE643_P06_V1_JadeSignalSafeSink {

    public void sinkJadeSignal(String data) throws XPathExpressionException {
        String jadeSignalXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeSignalXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeSignalXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeSignalTokens = data.split("||");
            if (jadeSignalTokens.length < 2) {
                return;
            }
            String jadeSignalUser = jadeSignalTokens[0];
            String jadeSignalPass = jadeSignalTokens[1];
            XPath jadeSignalXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeSignalXml = new InputSource(jadeSignalXmlFile);
            String jadeSignalQuery = "//users/user[name/text()='" + jadeSignalUser
                    + "' and pass/text()='" + jadeSignalPass + "']" + "/secret/text()";
            String jadeSignalSecret = (String) jadeSignalXPath.evaluate(jadeSignalQuery, jadeSignalXml, XPathConstants.STRING);
            System.out.println(jadeSignalSecret);
        }
    }
}
