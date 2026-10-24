import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicRaven {

    public void runMosaicRaven() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicRavenSource()).loadMosaicRaven();
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

class CWE89_P07_V1_MosaicRavenSource {
    public String loadMosaicRaven() {
        String data;
        data = System.getenv("MOSAIC_RAVEN_FILTER");
        return data;
    }
}
