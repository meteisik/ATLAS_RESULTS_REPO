import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneLotus {

    public void runRuneLotus() throws SQLException {
        String data;
        data = System.getenv("RUNE_LOTUS_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneLotusSink()).queryRuneLotus(dataArray);
    }
}

class CWE89_P08_V1_RuneLotusSink {
    public void queryRuneLotus(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        Statement runeLotusStatement = null;
        ResultSet runeLotusRows = null;
        try {
            runeLotusStatement = runeLotusConnection.createStatement();
            runeLotusRows = runeLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeLotusRows.getRow());
        } finally {
            if (runeLotusRows != null) {
                runeLotusRows.close();
            }
            if (runeLotusStatement != null) {
                runeLotusStatement.close();
            }
            runeLotusConnection.close();
        }
    }
}
