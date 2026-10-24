import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_ZephyrPrismSafe {
    private static int privateFive = 5;

    public void runZephyrPrism() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_ZephyrPrismSafeSink()).queryZephyrPrism(dataArray);
    }
}

class CWE89_P08_V2_ZephyrPrismSafeSink {
    public void queryZephyrPrism(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection zephyrPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrPrism");
        Statement zephyrPrismStatement = null;
        ResultSet zephyrPrismRows = null;
        try {
            zephyrPrismStatement = zephyrPrismConnection.createStatement();
            zephyrPrismRows = zephyrPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrPrismRows.getRow());
        } finally {
            if (zephyrPrismRows != null) {
                zephyrPrismRows.close();
            }
            if (zephyrPrismStatement != null) {
                zephyrPrismStatement.close();
            }
            zephyrPrismConnection.close();
        }
    }
}
