import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneLantern {

    public void runRuneLantern() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_LANTERN_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneLanternSink()).sinkRuneLantern(dataArray);
    }
}

class CWE643_P08_V1_RuneLanternSink {

    public void sinkRuneLantern(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String runeLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLanternTokens = data.split("||");
            if (runeLanternTokens.length < 2) {
                return;
            }
            String runeLanternUser = runeLanternTokens[0];
            String runeLanternPass = runeLanternTokens[1];
            XPath runeLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLanternXml = new InputSource(runeLanternXmlFile);
            String runeLanternQuery = "//users/user[name/text()='" + runeLanternUser
                    + "' and pass/text()='" + runeLanternPass + "']" + "/secret/text()";
            String runeLanternSecret = (String) runeLanternXPath.evaluate(runeLanternQuery, runeLanternXml, XPathConstants.STRING);
            System.out.println(runeLanternSecret);
        }
    }
}
