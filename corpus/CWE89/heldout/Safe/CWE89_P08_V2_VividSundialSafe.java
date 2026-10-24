import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_VividSundialSafe {

    public void runVividSundial() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_VividSundialSafeSink()).queryVividSundial(dataArray);
    }
}

class CWE89_P08_V2_VividSundialSafeSink {
    public void queryVividSundial(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        Statement vividSundialStatement = null;
        ResultSet vividSundialRows = null;
        try {
            vividSundialStatement = vividSundialConnection.createStatement();
            vividSundialRows = vividSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSundialRows.getRow());
        } finally {
            if (vividSundialRows != null) {
                vividSundialRows.close();
            }
            if (vividSundialStatement != null) {
                vividSundialStatement.close();
            }
            vividSundialConnection.close();
        }
    }
}
