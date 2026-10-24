import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneNebula {

    public static String data;

    public void runRuneNebula() throws SQLException {
        data = System.getenv("RUNE_NEBULA_FILTER");
        (new CWE89_P10_V1_RuneNebulaSink()).queryRuneNebula();
    }
}

class CWE89_P10_V1_RuneNebulaSink {
    public void queryRuneNebula() throws SQLException {
        String data = CWE89_P10_V1_RuneNebula.data;
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
