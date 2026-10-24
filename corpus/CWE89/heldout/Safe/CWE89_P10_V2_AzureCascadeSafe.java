import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureCascadeSafe {
    private static boolean privateTrue = true;

    public static String data;

    public void runAzureCascade() throws SQLException {
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureCascadeSafeSink()).queryAzureCascade();
    }
}

class CWE89_P10_V2_AzureCascadeSafeSink {
    public void queryAzureCascade() throws SQLException {
        String data = CWE89_P10_V2_AzureCascadeSafe.data;
        Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
        Statement azureCascadeStatement = null;
        ResultSet azureCascadeRows = null;
        try {
            azureCascadeStatement = azureCascadeConnection.createStatement();
            azureCascadeRows = azureCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureCascadeRows.getRow());
        } finally {
            if (azureCascadeRows != null) {
                azureCascadeRows.close();
            }
            if (azureCascadeStatement != null) {
                azureCascadeStatement.close();
            }
            azureCascadeConnection.close();
        }
    }
}
