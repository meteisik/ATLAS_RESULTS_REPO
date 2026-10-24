import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneNebulaSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneNebula() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneNebulaSafeSink()).queryRuneNebula(dataContainer);
    }
}

class CWE89_P09_V1_RuneNebulaSafeSink {
    public void queryRuneNebula(CWE89_P09_V1_RuneNebulaSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeNebula");
        Statement runeNebulaStatement = null;
        ResultSet runeNebulaRows = null;
        try {
            runeNebulaStatement = runeNebulaConnection.createStatement();
            runeNebulaRows = runeNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeNebulaRows.getRow());
        } finally {
            if (runeNebulaRows != null) {
                runeNebulaRows.close();
            }
            if (runeNebulaStatement != null) {
                runeNebulaStatement.close();
            }
            runeNebulaConnection.close();
        }
    }
}
