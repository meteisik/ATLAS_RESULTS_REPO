import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneHarborSafe {

    public void runRuneHarbor() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneHarborSafeSink()).queryRuneHarbor(dataArray);
    }
}

class CWE89_P08_V1_RuneHarborSafeSink {
    public void queryRuneHarbor(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        Statement runeHarborStatement = null;
        ResultSet runeHarborRows = null;
        try {
            runeHarborStatement = runeHarborConnection.createStatement();
            runeHarborRows = runeHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeHarborRows.getRow());
        } finally {
            if (runeHarborRows != null) {
                runeHarborRows.close();
            }
            if (runeHarborStatement != null) {
                runeHarborStatement.close();
            }
            runeHarborConnection.close();
        }
    }
}
