import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonLotusSafe {

    private void queryCrimsonLotus(String data) throws SQLException {
        Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
        Statement crimsonLotusStatement = null;
        ResultSet crimsonLotusRows = null;
        try {
            crimsonLotusStatement = crimsonLotusConnection.createStatement();
            crimsonLotusRows = crimsonLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonLotusRows.getRow());
        } finally {
            if (crimsonLotusRows != null) {
                crimsonLotusRows.close();
            }
            if (crimsonLotusStatement != null) {
                crimsonLotusStatement.close();
            }
            crimsonLotusConnection.close();
        }
    }

    public void runCrimsonLotus() throws SQLException {
        String data;
        data = "foo";
        queryCrimsonLotus(data);
    }
}
