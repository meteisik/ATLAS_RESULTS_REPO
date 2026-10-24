import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneHelix {

    public static String data;

    public void runRuneHelix() throws SQLException {
        data = System.getenv("RUNE_HELIX_FILTER");
        (new CWE89_P10_V1_RuneHelixSink()).queryRuneHelix();
    }
}

class CWE89_P10_V1_RuneHelixSink {
    public void queryRuneHelix() throws SQLException {
        String data = CWE89_P10_V1_RuneHelix.data;
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        Statement runeHelixStatement = null;
        ResultSet runeHelixRows = null;
        try {
            runeHelixStatement = runeHelixConnection.createStatement();
            runeHelixRows = runeHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeHelixRows.getRow());
        } finally {
            if (runeHelixRows != null) {
                runeHelixRows.close();
            }
            if (runeHelixStatement != null) {
                runeHelixStatement.close();
            }
            runeHelixConnection.close();
        }
    }
}
