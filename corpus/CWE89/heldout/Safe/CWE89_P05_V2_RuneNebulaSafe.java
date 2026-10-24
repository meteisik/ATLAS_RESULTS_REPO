import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_RuneNebulaSafe {

    private String runeNebulaData;

    private void queryRuneNebula() throws SQLException {
        String data = runeNebulaData;
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

    public void runRuneNebula() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        runeNebulaData = data;
        queryRuneNebula();
    }
}
