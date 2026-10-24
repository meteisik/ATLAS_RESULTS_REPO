import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureSundial {

    public void runAzureSundial() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("AZURE_SUNDIAL_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureSundialBase baseObject = new CWE89_P12_V2_AzureSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureSundialBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureSundialSink extends CWE89_P12_V2_AzureSundialBase {
    public void action(String data) throws SQLException {
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        Statement azureSundialStatement = null;
        ResultSet azureSundialRows = null;
        try {
            azureSundialStatement = azureSundialConnection.createStatement();
            azureSundialRows = azureSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureSundialRows.getRow());
        } finally {
            if (azureSundialRows != null) {
                azureSundialRows.close();
            }
            if (azureSundialStatement != null) {
                azureSundialStatement.close();
            }
            azureSundialConnection.close();
        }
    }
}
