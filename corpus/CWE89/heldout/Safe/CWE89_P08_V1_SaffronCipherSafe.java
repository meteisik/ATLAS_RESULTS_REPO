import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_SaffronCipherSafe {

    public void runSaffronCipher() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_SaffronCipherSafeSink()).querySaffronCipher(dataArray);
    }
}

class CWE89_P08_V1_SaffronCipherSafeSink {
    public void querySaffronCipher(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        Statement saffronCipherStatement = null;
        ResultSet saffronCipherRows = null;
        try {
            saffronCipherStatement = saffronCipherConnection.createStatement();
            saffronCipherRows = saffronCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronCipherRows.getRow());
        } finally {
            if (saffronCipherRows != null) {
                saffronCipherRows.close();
            }
            if (saffronCipherStatement != null) {
                saffronCipherStatement.close();
            }
            saffronCipherConnection.close();
        }
    }
}
