import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V2_MosaicNebula {
    private static int privateFive = 5;

    private void sinkMosaicNebula(String data) throws XPathExpressionException {
        String mosaicNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicNebulaTokens = data.split("||");
            if (mosaicNebulaTokens.length < 2) {
                return;
            }
            String mosaicNebulaUser = mosaicNebulaTokens[0];
            String mosaicNebulaPass = mosaicNebulaTokens[1];
            XPath mosaicNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicNebulaXml = new InputSource(mosaicNebulaXmlFile);
            String mosaicNebulaQuery = "//users/user[name/text()='" + mosaicNebulaUser
                    + "' and pass/text()='" + mosaicNebulaPass + "']" + "/secret/text()";
            String mosaicNebulaSecret = (String) mosaicNebulaXPath.evaluate(mosaicNebulaQuery, mosaicNebulaXml, XPathConstants.STRING);
            System.out.println(mosaicNebulaSecret);
        }
    }

    public void runMosaicNebula() throws XPathExpressionException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("MOSAIC_NEBULA_ADD");
        } else {
            data = null;
        }
        sinkMosaicNebula(data);
    }
}
