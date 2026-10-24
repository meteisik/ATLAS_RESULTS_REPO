import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V2_RuneComet {

    public void runRuneComet() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_COMET_ADD");
            break;
        default:
            data = null;
            break;
        }
        (new CWE643_P06_V2_RuneCometSink()).sinkRuneComet(data);
    }
}

class CWE643_P06_V2_RuneCometSink {

    public void sinkRuneComet(String data) throws XPathExpressionException {
        String runeCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeCometTokens = data.split("||");
            if (runeCometTokens.length < 2) {
                return;
            }
            String runeCometUser = runeCometTokens[0];
            String runeCometPass = runeCometTokens[1];
            XPath runeCometXPath = XPathFactory.newInstance().newXPath();
            InputSource runeCometXml = new InputSource(runeCometXmlFile);
            String runeCometQuery = "//users/user[name/text()='" + runeCometUser
                    + "' and pass/text()='" + runeCometPass + "']" + "/secret/text()";
            String runeCometSecret = (String) runeCometXPath.evaluate(runeCometQuery, runeCometXml, XPathConstants.STRING);
            System.out.println(runeCometSecret);
        }
    }
}
