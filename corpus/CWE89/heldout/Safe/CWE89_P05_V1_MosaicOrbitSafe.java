import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicOrbitSafe {

    private String mosaicOrbitData;

    private void queryMosaicOrbit() throws SQLException {
        String data = mosaicOrbitData;
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

    public void runMosaicOrbit() throws SQLException {
        String data;
        data = "foo";
        mosaicOrbitData = data;
        queryMosaicOrbit();
    }
}
