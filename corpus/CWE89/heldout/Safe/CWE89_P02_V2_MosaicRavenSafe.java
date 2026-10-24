import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicRavenSafe {
    private static int privateFive = 5;

    public void runMosaicRaven() throws SQLException {
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
            Connection mosaicRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicRaven");
            Statement mosaicRavenStatement = null;
            ResultSet mosaicRavenRows = null;
            try {
                mosaicRavenStatement = mosaicRavenConnection.createStatement();
                mosaicRavenRows = mosaicRavenStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicRavenRows.getRow());
            } finally {
                if (mosaicRavenRows != null) {
                    mosaicRavenRows.close();
                }
                if (mosaicRavenStatement != null) {
                    mosaicRavenStatement.close();
                }
                mosaicRavenConnection.close();
            }
        }
    }
}
