using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
//using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using StackExchange.Redis;
using System.Threading.Tasks;

namespace SfBTokenSvcPrototype.Utils
{
    public class DistributedTokenCache : TokenCache
    {
        private IDatabase cache;
        string UserObjectId = string.Empty;
        string CacheId = string.Empty;
        private static Lazy<ConnectionMultiplexer> connection;

      
        public DistributedTokenCache(string connstr, string userId)
        {
            connection = 
                new Lazy<ConnectionMultiplexer>(() => 
                ConnectionMultiplexer.Connect(connstr));
            cache = connection.Value.GetDatabase();
            UserObjectId = userId;
            CacheId = UserObjectId;
            this.AfterAccess = AfterAccessNotification;
            LoadFromCache();
        }

       

        public void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (this.HasStateChanged)
            {
                try
                {
                    if (this.Count > 0)
                    {
                        cache.StringSetAsync(CacheId,this.Serialize())
                            .GetAwaiter().GetResult();
 //                       _logger.TokensWrittenToStore(args.ClientId, args.UniqueId, args.Resource);
                    }
                    else
                    {
                        // There are no tokens for this user/client, so remove them from the cache.
                        // This was previously handled in an overridden Clear() method, but the built-in Clear() calls this
                        // after the dictionary is cleared.
                        cache.KeyDeleteAsync(CacheId)
                           .GetAwaiter().GetResult();
          //              _logger.TokenCacheCleared(_claimsPrincipal.GetObjectIdentifierValue(false) ?? "<none>");
                    }
                    this.HasStateChanged = false;
                }
                catch (Exception exp)
                {
             //       _logger.WriteToCacheFailed(exp);
                    throw;
                }
            }
        }


        public override void Clear()
        {
            base.Clear();
            cache.KeyDeleteAsync(CacheId)
                .GetAwaiter().GetResult();
        
        }
        private void LoadFromCache()
        {
            byte[] cacheData = cache.StringGetAsync(CacheId).GetAwaiter().GetResult();

            if (cacheData != null)
            {
                this.Deserialize(cacheData);
   //             _logger.TokensRetrievedFromStore(_cacheKey);
            }
        }
    }
}