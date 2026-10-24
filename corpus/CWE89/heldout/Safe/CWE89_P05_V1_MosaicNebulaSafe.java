import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicNebulaSafe {

    private String mosaicNebulaData;

    private void queryMosaicNebula() throws SQLException {
        String data = mosaicNebulaData;
        Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
        Statement mosaicNebulaStatement = null;
        ResultSet mosaicNebulaRows = null;
        try {
            mosaicNebulaStatement = mosaicNebulaConnection.createStatement();
            mosaicNebulaRows = mosaicNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicNebulaRows.getRow());
        } finally {
            if (mosaicNebulaRows != null) {
                mosaicNebulaRows.close();
            }
            if (mosaicNebulaStatement != null) {
                mosaicNebulaStatement.close();
            }
            mosaicNebulaConnection.close();
        }
    }

    public void runMosaicNebula() throws SQLException {
        String data;
        data = "foo";
        mosaicNebulaData = data;
        queryMosaicNebula();
    }
}
