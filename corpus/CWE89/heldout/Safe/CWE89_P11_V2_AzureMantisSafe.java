import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureMantis() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AzureMantisSafeSink()).queryAzureMantis(dataHashMap);
    }
}

class CWE89_P11_V2_AzureMantisSafeSink {
    public void queryAzureMantis(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
        Statement azureMantisStatement = null;
        ResultSet azureMantisRows = null;
        try {
            azureMantisStatement = azureMantisConnection.createStatement();
            azureMantisRows = azureMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureMantisRows.getRow());
        } finally {
            if (azureMantisRows != null) {
                azureMantisRows.close();
            }
            if (azureMantisStatement != null) {
                azureMantisStatement.close();
            }
            azureMantisConnection.close();
        }
    }
}
