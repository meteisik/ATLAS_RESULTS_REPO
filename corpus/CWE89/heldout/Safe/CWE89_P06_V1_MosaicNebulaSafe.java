import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicNebulaSafe {

    public void runMosaicNebula() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicNebulaSafeSink()).queryMosaicNebula(data);
    }
}

class CWE89_P06_V1_MosaicNebulaSafeSink {
    public void queryMosaicNebula(String data) throws SQLException {
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
}
