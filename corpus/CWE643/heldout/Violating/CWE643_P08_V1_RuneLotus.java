import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_RuneLotus {

    public void runRuneLotus() throws XPathExpressionException {
        String data;
        data = System.getenv("RUNE_LOTUS_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_RuneLotusSink()).sinkRuneLotus(dataArray);
    }
}

class CWE643_P08_V1_RuneLotusSink {

    public void sinkRuneLotus(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String runeLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLotusTokens = data.split("||");
            if (runeLotusTokens.length < 2) {
                return;
            }
            String runeLotusUser = runeLotusTokens[0];
            String runeLotusPass = runeLotusTokens[1];
            XPath runeLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLotusXml = new InputSource(runeLotusXmlFile);
            String runeLotusQuery = "//users/user[name/text()='" + runeLotusUser
                    + "' and pass/text()='" + runeLotusPass + "']" + "/secret/text()";
            String runeLotusSecret = (String) runeLotusXPath.evaluate(runeLotusQuery, runeLotusXml, XPathConstants.STRING);
            System.out.println(runeLotusSecret);
        }
    }
}
