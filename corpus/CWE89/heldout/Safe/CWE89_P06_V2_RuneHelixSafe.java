import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneHelixSafe {

    public void runRuneHelix() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE89_P06_V2_RuneHelixSafeSink()).queryRuneHelix(data);
    }
}

class CWE89_P06_V2_RuneHelixSafeSink {
    public void queryRuneHelix(String data) throws SQLException {
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
