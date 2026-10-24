import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_SaffronGlintSafe {

    public void runSaffronGlint() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_SaffronGlintSafeSink()).querySaffronGlint(dataArray);
    }
}

class CWE89_P08_V1_SaffronGlintSafeSink {
    public void querySaffronGlint(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        Statement saffronGlintStatement = null;
        ResultSet saffronGlintRows = null;
        try {
            saffronGlintStatement = saffronGlintConnection.createStatement();
            saffronGlintRows = saffronGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronGlintRows.getRow());
        } finally {
            if (saffronGlintRows != null) {
                saffronGlintRows.close();
            }
            if (saffronGlintStatement != null) {
                saffronGlintStatement.close();
            }
            saffronGlintConnection.close();
        }
    }
}
