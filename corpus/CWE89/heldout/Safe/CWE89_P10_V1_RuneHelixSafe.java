import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_RuneHelixSafe {

    public static String data;

    public void runRuneHelix() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_RuneHelixSafeSink()).queryRuneHelix();
    }
}

class CWE89_P10_V1_RuneHelixSafeSink {
    public void queryRuneHelix() throws SQLException {
        String data = CWE89_P10_V1_RuneHelixSafe.data;
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
