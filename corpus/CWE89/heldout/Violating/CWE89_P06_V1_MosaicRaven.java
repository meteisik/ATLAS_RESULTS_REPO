import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicRaven {

    public void runMosaicRaven() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_RAVEN_FILTER");
        (new CWE89_P06_V1_MosaicRavenSink()).queryMosaicRaven(data);
    }
}

class CWE89_P06_V1_MosaicRavenSink {
    public void queryMosaicRaven(String data) throws SQLException {
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
