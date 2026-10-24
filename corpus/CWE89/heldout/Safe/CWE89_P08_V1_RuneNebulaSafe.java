import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneNebulaSafe {

    public void runRuneNebula() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneNebulaSafeSink()).queryRuneNebula(dataArray);
    }
}

class CWE89_P08_V1_RuneNebulaSafeSink {
    public void queryRuneNebula(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
