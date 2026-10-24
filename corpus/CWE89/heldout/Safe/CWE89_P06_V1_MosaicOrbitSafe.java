import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicOrbitSafe {

    public void runMosaicOrbit() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicOrbitSafeSink()).queryMosaicOrbit(data);
    }
}

class CWE89_P06_V1_MosaicOrbitSafeSink {
    public void queryMosaicOrbit(String data) throws SQLException {
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
