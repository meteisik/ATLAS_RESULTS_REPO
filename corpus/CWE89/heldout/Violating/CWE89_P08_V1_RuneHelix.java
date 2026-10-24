import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneHelix {

    public void runRuneHelix() throws SQLException {
        String data;
        data = System.getenv("RUNE_HELIX_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneHelixSink()).queryRuneHelix(dataArray);
    }
}

class CWE89_P08_V1_RuneHelixSink {
    public void queryRuneHelix(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
