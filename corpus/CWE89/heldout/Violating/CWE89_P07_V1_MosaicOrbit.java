import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicOrbit {

    public void runMosaicOrbit() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicOrbitSource()).loadMosaicOrbit();
        Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
        Statement mosaicOrbitStatement = null;
        ResultSet mosaicOrbitRows = null;
        try {
            mosaicOrbitStatement = mosaicOrbitConnection.createStatement();
            mosaicOrbitRows = mosaicOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicOrbitRows.getRow());
        } finally {
            if (mosaicOrbitRows != null) {
                mosaicOrbitRows.close();
            }
            if (mosaicOrbitStatement != null) {
                mosaicOrbitStatement.close();
            }
            mosaicOrbitConnection.close();
        }
    }
}

class CWE89_P07_V1_MosaicOrbitSource {
    public String loadMosaicOrbit() {
        String data;
        data = System.getenv("MOSAIC_ORBIT_FILTER");
        return data;
    }
}
