import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_RuneNebula {
    private static int privateFive = 5;

    public void runRuneNebula() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = (new CWE89_P07_V2_RuneNebulaSource()).loadRuneNebula();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_RuneNebulaSource {
    public String loadRuneNebula() {
        String data;
        data = System.getenv("RUNE_NEBULA_FILTER");
        return data;
    }
}
