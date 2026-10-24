import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_ZephyrGlintSafe {
    private static boolean privateTrue = true;

    public void runZephyrGlint() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_ZephyrGlintSafeSink()).queryZephyrGlint(dataArray);
    }
}

class CWE89_P08_V2_ZephyrGlintSafeSink {
    public void queryZephyrGlint(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        Statement zephyrGlintStatement = null;
        ResultSet zephyrGlintRows = null;
        try {
            zephyrGlintStatement = zephyrGlintConnection.createStatement();
            zephyrGlintRows = zephyrGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrGlintRows.getRow());
        } finally {
            if (zephyrGlintRows != null) {
                zephyrGlintRows.close();
            }
            if (zephyrGlintStatement != null) {
                zephyrGlintStatement.close();
            }
            zephyrGlintConnection.close();
        }
    }
}
