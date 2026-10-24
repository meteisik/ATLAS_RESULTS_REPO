import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P08_V1_SaffronCascade {

    public void runSaffronCascade() throws XPathExpressionException {
        String data;
        data = System.getenv("SAFFRON_CASCADE_ADD");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE643_P08_V1_SaffronCascadeSink()).sinkSaffronCascade(dataArray);
    }
}

class CWE643_P08_V1_SaffronCascadeSink {

    public void sinkSaffronCascade(String[] dataArray) throws XPathExpressionException {
        String data = dataArray[2];
        String saffronCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCascadeTokens = data.split("||");
            if (saffronCascadeTokens.length < 2) {
                return;
            }
            String saffronCascadeUser = saffronCascadeTokens[0];
            String saffronCascadePass = saffronCascadeTokens[1];
            XPath saffronCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCascadeXml = new InputSource(saffronCascadeXmlFile);
            String saffronCascadeQuery = "//users/user[name/text()='" + saffronCascadeUser
                    + "' and pass/text()='" + saffronCascadePass + "']" + "/secret/text()";
            String saffronCascadeSecret = (String) saffronCascadeXPath.evaluate(saffronCascadeQuery, saffronCascadeXml, XPathConstants.STRING);
            System.out.println(saffronCascadeSecret);
        }
    }
}
